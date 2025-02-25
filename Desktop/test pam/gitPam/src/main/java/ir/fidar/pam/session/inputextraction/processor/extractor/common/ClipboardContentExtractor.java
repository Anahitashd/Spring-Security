package ir.fidar.pam.session.inputextraction.processor.extractor.common;

import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputProcessingStatus;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.apache.guacamole.protocol.GuacamoleInstruction;

public class ClipboardContentExtractor implements InputExtractor<String> {
   @Override
   public boolean extractable(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return instruction.getOpcode().equalsIgnoreCase("blob")
         && remoteSessionInputExtraction.getInputStatus().equals(ConsoleTypeRemoteSessionInputProcessingStatus.CLIPBOARD);
   }

   public String extract(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return new String(Base64.getDecoder().decode((String)instruction.getArgs().get(1)), StandardCharsets.UTF_8);
   }
}
