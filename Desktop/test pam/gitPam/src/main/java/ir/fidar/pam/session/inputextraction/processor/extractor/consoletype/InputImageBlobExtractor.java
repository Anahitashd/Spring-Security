package ir.fidar.pam.session.inputextraction.processor.extractor.consoletype;

import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputProcessingStatus;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import org.apache.guacamole.protocol.GuacamoleInstruction;

public class InputImageBlobExtractor implements InputExtractor<String> {
   @Override
   public boolean extractable(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return remoteSessionInputExtraction.getInputStatus().equals(ConsoleTypeRemoteSessionInputProcessingStatus.IMAGE_IMG)
         && instruction.getOpcode().equals("blob");
   }

   public String extract(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return (String)instruction.getArgs().get(1);
   }
}
