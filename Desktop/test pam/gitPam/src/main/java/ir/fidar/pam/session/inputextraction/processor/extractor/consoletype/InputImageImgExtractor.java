package ir.fidar.pam.session.inputextraction.processor.extractor.consoletype;

import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputProcessingStatus;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import org.apache.guacamole.protocol.GuacamoleInstruction;

public class InputImageImgExtractor implements InputExtractor<Void> {
   @Override
   public boolean extractable(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return remoteSessionInputExtraction.getInputStatus().equals(ConsoleTypeRemoteSessionInputProcessingStatus.IMAGE_CFILL)
         && instruction.getOpcode().equals("img");
   }

   public Void extract(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return null;
   }
}
