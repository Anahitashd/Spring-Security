package ir.fidar.pam.session.inputextraction.processor.consoletype;

import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputProcessingStatus;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import ir.fidar.pam.session.inputextraction.processor.extractor.consoletype.InputImageCfillExtractor;

public class InputImageCfillInstructionProcessor extends AbstractConsoleTypeInstructionProcessor<Void> {
   @Override
   protected InputExtractor<Void> getExtractor() {
      return new InputImageCfillExtractor();
   }

   protected void processExtractedInput(Void input, InputSource source, ConsoleTypeRemoteSessionInputExtraction remoteSessionInputExtraction) {
      remoteSessionInputExtraction.setInputStatus(ConsoleTypeRemoteSessionInputProcessingStatus.IMAGE_CFILL);
   }

   public int getOrder() {
      return 3;
   }
}
