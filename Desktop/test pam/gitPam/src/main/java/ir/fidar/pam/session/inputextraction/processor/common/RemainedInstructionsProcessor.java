package ir.fidar.pam.session.inputextraction.processor.common;

import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputProcessingStatus;
import ir.fidar.pam.session.inputextraction.processor.AbstractCommonSessionTypeInstructionProcessor;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import ir.fidar.pam.session.inputextraction.processor.extractor.common.RemainedInstructionsExtractor;

public class RemainedInstructionsProcessor extends AbstractCommonSessionTypeInstructionProcessor<Void> {
   @Override
   protected InputExtractor<Void> getExtractor() {
      return new RemainedInstructionsExtractor();
   }

   protected void processExtractedInput(Void input, InputSource source, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      remoteSessionInputExtraction.setInputStatus(RemoteSessionInputProcessingStatus.NONE);
   }

   public int getOrder() {
      return 100;
   }
}
