package ir.fidar.pam.session.inputextraction.processor.consoletype;

import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputProcessingStatus;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import ir.fidar.pam.session.inputextraction.processor.extractor.consoletype.InputImageImgExtractor;

public class InputImageImgInstructionProcessor extends AbstractConsoleTypeInstructionProcessor<Void> {
   @Override
   protected InputExtractor<Void> getExtractor() {
      return new InputImageImgExtractor();
   }

   protected void processExtractedInput(Void input, InputSource source, ConsoleTypeRemoteSessionInputExtraction remoteSessionInputExtraction) {
      remoteSessionInputExtraction.setInputStatus(ConsoleTypeRemoteSessionInputProcessingStatus.IMAGE_IMG);
   }

   public int getOrder() {
      return 4;
   }
}
