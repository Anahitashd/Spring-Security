package ir.fidar.pam.session.inputextraction.processor.extractor.common;

import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import org.apache.guacamole.protocol.GuacamoleInstruction;

public class SyncExtractor implements InputExtractor<Long> {
   @Override
   public boolean extractable(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return remoteSessionInputExtraction.getBaseTime() == 0L && instruction.getOpcode().equalsIgnoreCase("sync");
   }

   public Long extract(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return Long.parseLong((String)instruction.getArgs().get(0));
   }
}
