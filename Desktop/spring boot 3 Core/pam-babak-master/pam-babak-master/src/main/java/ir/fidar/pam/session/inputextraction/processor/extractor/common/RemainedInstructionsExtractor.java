package ir.fidar.pam.session.inputextraction.processor.extractor.common;

import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import org.apache.guacamole.protocol.GuacamoleInstruction;

public class RemainedInstructionsExtractor implements InputExtractor<Void> {
   @Override
   public boolean extractable(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return true;
   }

   public Void extract(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return null;
   }
}
